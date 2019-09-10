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

struct aead_crypto_context_t
{
  ptls_aead_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

vnet_crypto_main_t *cm = &crypto_main;

typedef struct quic_decrypt_cb_ctx_
{
  quicly_conn_t *conn;
  quicly_decoded_packet_t *packet;
  quicly_pn_space_t *space;
  size_t epoch;
  uint64_t pn;
  size_t aead_off;
  size_t ptlen;
} quic_decrypt_cb_ctx;

typedef struct quic_encrypt_cb_ctx_
{
  ptls_cipher_context_t *header_protection;
  uint8_t *first_byte_at;
  uint8_t *dst_payload_from;
} quic_encrypt_cb_ctx;

struct st_quic_crypto_codec_t
{
  quicly_crypto_codec_t super;
};

typedef struct quic_crypto_op_
{
  vnet_crypto_op_t *aead_op;
  u8 iv[PTLS_MAX_IV_SIZE];
  u32 key_index;
  quicly_crypto_codec_t *crypto_codec;
  quic_decrypt_cb_ctx decrypt_cb_ctx;
  quic_encrypt_cb_ctx encrypt_cb_ctx;
} quic_crypto_op_t;

vnet_crypto_op_t aead_crypto_ops[QUIC_SEND_MAX_BATCH_PACKETS];
vnet_crypto_op_t aead_decrypt_ops[QUIC_RCV_MAX_BATCH_PACKETS];

size_t crypto_op_count = 0;
size_t decrypt_op_count = 0;

quic_crypto_op_t crypto_ops[QUIC_SEND_MAX_BATCH_PACKETS];
quic_crypto_op_t decrypt_ops[QUIC_RCV_MAX_BATCH_PACKETS];

void
quic_crypto_process ()
{
  vlib_main_t *vm = vlib_get_main ();

  if (crypto_op_count <= 0)
    return;

  vnet_crypto_process_ops (vm, aead_crypto_ops, crypto_op_count);

  for (int i = 0; i < crypto_op_count; i++)
    {
      quic_crypto_op_t *cur_op = &crypto_ops[i];
      cur_op->crypto_codec->encrypt_packet_done (crypto_ops[i].encrypt_cb_ctx.
						 header_protection,
						 crypto_ops[i].encrypt_cb_ctx.
						 first_byte_at,
						 crypto_ops[i].encrypt_cb_ctx.
						 dst_payload_from);
    }

  crypto_op_count = 0;
}

void
quic_decrypt_process ()
{
  QUIC_DBG (1, "[quic] %s", __FUNCTION__);
  vlib_main_t *vm = vlib_get_main ();

  if (decrypt_op_count <= 0)
    return;

  vnet_crypto_process_ops (vm, aead_decrypt_ops, decrypt_op_count);
  for (int i = 0; i < decrypt_op_count; i++)
    {
      quic_crypto_op_t *cur_op = &decrypt_ops[i];
      cur_op->crypto_codec->decrypt_packet_done (decrypt_ops[i].
						 decrypt_cb_ctx.conn,
						 decrypt_ops[i].
						 decrypt_cb_ctx.packet,
						 decrypt_ops[i].
						 decrypt_cb_ctx.space,
						 decrypt_ops[i].
						 decrypt_cb_ctx.epoch,
						 decrypt_ops[i].
						 decrypt_cb_ctx.pn,
						 decrypt_ops[i].
						 decrypt_cb_ctx.aead_off,
						 decrypt_ops[i].
						 decrypt_cb_ctx.ptlen);
    }

  decrypt_op_count = 0;
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
quic_crypto_codec_packet_encrypt_done (ptls_cipher_context_t *
				       header_protection,
				       uint8_t * first_byte_at,
				       uint8_t * dst_payload_from)
{
  /* apply header protection */
  uint8_t hpmask[1 + QUICLY_SEND_PN_SIZE] = { 0 };
  ptls_cipher_init (header_protection,
		    dst_payload_from - QUICLY_SEND_PN_SIZE +
		    QUICLY_MAX_PN_SIZE);
  ptls_cipher_encrypt (header_protection, hpmask, hpmask, sizeof (hpmask));

  *first_byte_at ^=
    hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER (*first_byte_at) ? 0xf : 0x1f);
  size_t i;
  for (i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
    dst_payload_from[i - QUICLY_SEND_PN_SIZE] ^= hpmask[i + 1];
}

static size_t
quic_codec_packet_encrypt (quicly_crypto_codec_t * _self,
			   ptls_aead_context_t * aead,
			   ptls_cipher_context_t * header_protection,
			   uint8_t * dst, uint8_t * dst_payload_from,
			   uint8_t * first_byte_at, uint64_t packet_number)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) aead;

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
  crypto_ops[crypto_op_count].aead_op = vnet_op;
  crypto_ops[crypto_op_count].crypto_codec = _self;
  crypto_ops[crypto_op_count].encrypt_cb_ctx.header_protection =
    header_protection;
  crypto_ops[crypto_op_count].encrypt_cb_ctx.dst_payload_from =
    dst_payload_from;
  crypto_ops[crypto_op_count].encrypt_cb_ctx.first_byte_at = first_byte_at;

  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) first_byte_at;
  vnet_op->aad_len = dst_payload_from - first_byte_at;
  build_iv (aead, crypto_ops[crypto_op_count].iv, packet_number);
  vnet_op->iv = (u8 *) crypto_ops[crypto_op_count].iv;
  vnet_op->src = dst_payload_from;
  vnet_op->dst = dst_payload_from;
  vnet_op->key_index = ctx->key_index;
  vnet_op->len = dst - dst_payload_from;

  vnet_op->tag_len = ctx->super.algo->tag_size;
  vnet_op->tag = vnet_op->src + vnet_op->len;

  crypto_op_count++;
  if (crypto_op_count == QUIC_SEND_MAX_BATCH_PACKETS)
    quic_crypto_process ();

  return vnet_op->len + vnet_op->tag_len;
}

static int
quic_codec_packet_decrypt (quicly_crypto_codec_t * _self,
			   quicly_conn_t * conn, quicly_pn_space_t * space,
			   ptls_cipher_context_t * header_protection,
			   ptls_aead_context_t ** aead, size_t epoch,
			   uint64_t * next_expected_pn,
			   quicly_decoded_packet_t * packet)
{
  size_t encrypted_len = packet->octets.len - packet->encrypted_off;
  uint8_t hpmask[5] = { 0 };
  uint32_t pnbits = 0;
  size_t pnlen, aead_index, i;
  size_t ptlen;
  uint64_t pn;

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
  pn = quicly_determine_packet_number (pnbits, pnlen * 8, *next_expected_pn);
  size_t aead_off = packet->encrypted_off + pnlen;

  struct aead_crypto_context_t *aead_ctx =
    (struct aead_crypto_context_t *) aead[aead_index];
  vnet_crypto_op_id_t id;
  if (!strcmp (aead_ctx->super.algo->name, "AES128-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_128_GCM_DEC;
    }
  else if (!strcmp (aead_ctx->super.algo->name, "AES256-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_256_GCM_DEC;
    }
  else
    {
      assert (0);
    }

  u8 *in_out = packet->octets.base + aead_off;
  size_t inlen = packet->octets.len - aead_off;
  ptlen = inlen - aead_ctx->super.algo->tag_size;

  vnet_crypto_op_t *vnet_op = &aead_decrypt_ops[decrypt_op_count];
  decrypt_ops[decrypt_op_count].aead_op = vnet_op;
  decrypt_ops[decrypt_op_count].crypto_codec = _self;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.aead_off = aead_off;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.conn = conn;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.epoch = epoch;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.packet = packet;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.pn = pn;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.ptlen = ptlen;
  decrypt_ops[decrypt_op_count].decrypt_cb_ctx.space = space;

  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) packet->octets.base;
  vnet_op->aad_len = aead_off;
  build_iv (aead[aead_index], decrypt_ops[decrypt_op_count].iv, pn);
  vnet_op->iv = (u8 *) decrypt_ops[decrypt_op_count].iv;
  vnet_op->src = in_out;
  vnet_op->dst = in_out;
  vnet_op->key_index = aead_ctx->key_index;
  vnet_op->len = ptlen;
  vnet_op->tag_len = aead_ctx->super.algo->tag_size;
  vnet_op->tag = vnet_op->src + vnet_op->len;

  decrypt_op_count++;
  if (decrypt_op_count == QUIC_RCV_MAX_BATCH_PACKETS)
    quic_decrypt_process ();

  if (ptlen == SIZE_MAX)
    {
      if (QUICLY_DEBUG)
	fprintf (stderr, "%s: aead decryption failure (pn: %" PRIu64 ")\n",
		 __FUNCTION__, pn);
      goto Error;
    }

  return 0;

Error:
  return 1;
}

quicly_crypto_codec_t *
quic_new_crypto_codec ()
{
  struct st_quic_crypto_codec_t *self = NULL;
  if ((self = malloc (sizeof (*self))) == NULL)
    goto Exit;

/* *INDENT-OFF* */
  *self = (struct st_quic_crypto_codec_t){{quic_codec_packet_encrypt, quic_crypto_codec_packet_encrypt_done, quic_codec_packet_decrypt, NULL}};
/* *INDENT-ON* */

Exit:
  return &self->super;
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

  vnet_crypto_op_init (&ctx->op, id);
  ctx->op.aad = (u8 *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.iv = (u8 *) iv;
  ctx->op.key_index = ctx->key_index;
}

size_t
quic_crypto_aead_encrypt_update (ptls_aead_context_t * _ctx, void *output,
				 const void *input, size_t inlen)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  ctx->op.src = (u8 *) input;
  ctx->op.dst = output;
  ctx->op.key_index = ctx->key_index;
  ctx->op.len = inlen;

  ctx->op.tag_len = ctx->super.algo->tag_size;
  ctx->op.tag = ctx->op.src + inlen;

  return 0;
}

size_t
quic_crypto_aead_encrypt_final (ptls_aead_context_t * _ctx, void *output)
{
  vlib_main_t *vm = vlib_get_main ();
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

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

ptls_aead_algorithm_t quic_crypto_aes128gcm = { "AES128-GCM",
  &ptls_openssl_aes128ctr,
  NULL,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = { "AES256-GCM",
  &ptls_openssl_aes256ctr,
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
