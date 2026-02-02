/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Rubicon Communications, LLC.
 */

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_chachapoly.h>
#include <wireguard/wireguard_hchacha20.h>

bool
wg_chacha20poly1305_calc (vlib_main_t *vm, u8 *src, u32 src_len, u8 *dst, u8 *aad, u32 aad_len,
			  u64 nonce, vnet_crypto_op_id_t op_id, vnet_crypto_key_t *key)
{
  vnet_crypto_op_t _op, *op = &_op;
  u8 iv[12];
  u8 tag_[NOISE_AUTHTAG_LEN] = {};
  u8 src_[] = {};

  clib_memset (iv, 0, 12);
  clib_memcpy (iv + 4, &nonce, sizeof (nonce));

  vnet_crypto_op_init (op, op_id);

  op->tag_len = NOISE_AUTHTAG_LEN;
  if (op_id == VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC)
    {
      op->tag = src + src_len - NOISE_AUTHTAG_LEN;
      src_len -= NOISE_AUTHTAG_LEN;
      op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
    }
  else
    op->tag = tag_;

  op->src = !src ? src_ : src;
  op->len = src_len;

  op->dst = dst;
  op->key_data = vnet_crypto_get_key_data (vm, key, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  op->aad = aad;
  op->aad_len = aad_len;
  op->iv = iv;

  vnet_crypto_process_ops (op, 1);
  if (op_id == VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC)
    {
      clib_memcpy (dst + src_len, op->tag, NOISE_AUTHTAG_LEN);
    }

  return (op->status == VNET_CRYPTO_OP_STATUS_COMPLETED);
}

void
wg_xchacha20poly1305_encrypt (vlib_main_t *vm, u8 *src, u32 src_len, u8 *dst,
			      u8 *aad, u32 aad_len,
			      u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			      u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  int i;
  u32 derived_key[CHACHA20POLY1305_KEY_SIZE / sizeof (u32)];
  u64 h_nonce;

  clib_memcpy (&h_nonce, nonce + 16, sizeof (h_nonce));
  h_nonce = clib_little_to_host_u64 (h_nonce);
  hchacha20 (derived_key, nonce, key);

  for (i = 0; i < (sizeof (derived_key) / sizeof (derived_key[0])); i++)
    (derived_key[i]) = clib_host_to_little_u32 ((derived_key[i]));

  vnet_crypto_key_t *vnet_key = vnet_crypto_key_add_ptr (
    VNET_CRYPTO_ALG_CHACHA20_POLY1305, (uint8_t *) derived_key, CHACHA20POLY1305_KEY_SIZE);

  wg_chacha20poly1305_calc (vm, src, src_len, dst, aad, aad_len, h_nonce,
			    VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC, vnet_key);

  vnet_crypto_key_del_ptr (vnet_key);
  wg_secure_zero_memory (derived_key, CHACHA20POLY1305_KEY_SIZE);
}

bool
wg_xchacha20poly1305_decrypt (vlib_main_t *vm, u8 *src, u32 src_len, u8 *dst,
			      u8 *aad, u32 aad_len,
			      u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			      u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  int ret, i;
  u32 derived_key[CHACHA20POLY1305_KEY_SIZE / sizeof (u32)];
  u64 h_nonce;

  clib_memcpy (&h_nonce, nonce + 16, sizeof (h_nonce));
  h_nonce = clib_little_to_host_u64 (h_nonce);
  hchacha20 (derived_key, nonce, key);

  for (i = 0; i < (sizeof (derived_key) / sizeof (derived_key[0])); i++)
    (derived_key[i]) = clib_host_to_little_u32 ((derived_key[i]));

  vnet_crypto_key_t *vnet_key = vnet_crypto_key_add_ptr (
    VNET_CRYPTO_ALG_CHACHA20_POLY1305, (uint8_t *) derived_key, CHACHA20POLY1305_KEY_SIZE);

  ret = wg_chacha20poly1305_calc (vm, src, src_len, dst, aad, aad_len, h_nonce,
				  VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC, vnet_key);

  vnet_crypto_key_del_ptr (vnet_key);
  wg_secure_zero_memory (derived_key, CHACHA20POLY1305_KEY_SIZE);

  return ret;
}
