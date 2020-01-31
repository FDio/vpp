/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifdef __aarch64__

static_always_inline void
aes_cbc_dec (u8x16 * k, u8 * src, u8 * dst, u8 * iv, int count, int rounds)
{
  u8x16 r0, r1, r2, r3, c0, c1, c2, c3, f;

  f = vld1q_u8 (iv);

  while (count >= 64)
    {
      c0 = r0 = vld1q_u8 (src);
      c1 = r1 = vld1q_u8 (src + 16);
      c2 = r2 = vld1q_u8 (src + 32);
      c3 = r3 = vld1q_u8 (src + 48);
      for (int i = 0; i < rounds - 1; i++)
	{
	  r0 = vaesimcq_u8 (vaesdq_u8 (r0, k[i]));
	  r1 = vaesimcq_u8 (vaesdq_u8 (r1, k[i]));
	  r2 = vaesimcq_u8 (vaesdq_u8 (r2, k[i]));
	  r3 = vaesimcq_u8 (vaesdq_u8 (r3, k[i]));
	}
      r0 = vaesdq_u8 (r0, k[rounds - 1]) ^ k[rounds];
      r1 = vaesdq_u8 (r1, k[rounds - 1]) ^ k[rounds];
      r2 = vaesdq_u8 (r2, k[rounds - 1]) ^ k[rounds];
      r3 = vaesdq_u8 (r3, k[rounds - 1]) ^ k[rounds];
      vst1q_u8 (dst, r0 ^ f);
      vst1q_u8 (dst + 16, r1 ^ c0);
      vst1q_u8 (dst + 32, r2 ^ c1);
      vst1q_u8 (dst + 48, r3 ^ c2);
      f = c3;

      src += 64;
      dst += 64;
      count -= 64;
    }

  while (count >= 16)
    {
      c0 = r0 = vld1q_u8 (src);
      for (int i = 0; i < rounds - 1; i++)
	r0 = vaesimcq_u8 (vaesdq_u8 (r0, k[i]));
      r0 = vaesdq_u8 (r0, k[rounds - 1]) ^ k[rounds];
      vst1q_u8 (dst, r0 ^ f);
      f = c0;

      src += 16;
      dst += 16;
      count -= 16;
    }
}

static_always_inline u32
aesni_ops_enc_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd =
    vec_elt_at_index (cm->per_thread_data, vm->thread_index);
  int rounds = AES_KEY_ROUNDS (ks);
  u8 dummy[8192];
  u32 i, j, count, n_left = n_ops;
  u32x4 dummy_mask = { };
  u32x4 len = { };
  vnet_crypto_key_index_t key_index[4];
  u8 *src[4] = { };
  u8 *dst[4] = { };
  u8x16 r[4] = { };
  u8x16 k[15][4] = { };

  for (i = 0; i < 4; i++)
    key_index[i] = ~0;

more:
  for (i = 0; i < 4; i++)
    if (len[i] == 0)
      {
	if (n_left == 0)
	  {
	    /* no more work to enqueue, so we are enqueueing dummy buffer */
	    src[i] = dst[i] = dummy;
	    len[i] = sizeof (dummy);
	    dummy_mask[i] = 0;
	  }
	else
	  {
	    if (ops[0]->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	      {
		r[i] = ptd->cbc_iv[i];
		vst1q_u8 (ops[0]->iv, r[i]);
		ptd->cbc_iv[i] = vaeseq_u8 (r[i], r[i]);
	      }
	    else
	      r[i] = vld1q_u8 (ops[0]->iv);

	    src[i] = ops[0]->src;
	    dst[i] = ops[0]->dst;
	    len[i] = ops[0]->len;
	    dummy_mask[i] = ~0;
	    if (key_index[i] != ops[0]->key_index)
	      {
		aes_cbc_key_data_t *kd;
		key_index[i] = ops[0]->key_index;
		kd = (aes_cbc_key_data_t *) cm->key_data[key_index[i]];
		for (j = 0; j < rounds + 1; j++)
		  k[j][i] = kd->encrypt_key[j];
	      }
	    ops[0]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
	    n_left--;
	    ops++;
	  }
      }

  count = u32x4_min_scalar (len);

  ASSERT (count % 16 == 0);

  for (i = 0; i < count; i += 16)
    {
      r[0] ^= vld1q_u8 (src[0] + i);
      r[1] ^= vld1q_u8 (src[1] + i);
      r[2] ^= vld1q_u8 (src[2] + i);
      r[3] ^= vld1q_u8 (src[3] + i);
      for (j = 0; j < rounds - 1; j++)
	{
	  r[0] = vaesmcq_u8 (vaeseq_u8 (r[0], k[j][0]));
	  r[1] = vaesmcq_u8 (vaeseq_u8 (r[1], k[j][1]));
	  r[2] = vaesmcq_u8 (vaeseq_u8 (r[2], k[j][2]));
	  r[3] = vaesmcq_u8 (vaeseq_u8 (r[3], k[j][3]));
	}
      r[0] = vaeseq_u8 (r[0], k[j][0]) ^ k[rounds][0];
      r[1] = vaeseq_u8 (r[1], k[j][1]) ^ k[rounds][1];
      r[2] = vaeseq_u8 (r[2], k[j][2]) ^ k[rounds][2];
      r[3] = vaeseq_u8 (r[3], k[j][3]) ^ k[rounds][3];
      vst1q_u8 (dst[0] + i, r[0]);
      vst1q_u8 (dst[1] + i, r[1]);
      vst1q_u8 (dst[2] + i, r[2]);
      vst1q_u8 (dst[3] + i, r[3]);
    }

  for (i = 0; i < 4; i++)
    {
      src[i] += count;
      dst[i] += count;
      len[i] -= count;
    }

  if (n_left > 0)
    goto more;

  if (!u32x4_is_all_zero (len & dummy_mask))
    goto more;

  return n_ops;
}

static_always_inline u32
aesni_ops_dec_aes_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		       u32 n_ops, aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;
  int rounds = AES_KEY_ROUNDS (ks);
  vnet_crypto_op_t *op = ops[0];
  aes_cbc_key_data_t *kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
  u32 n_left = n_ops;

  ASSERT (n_ops >= 1);

decrypt:
  aes_cbc_dec (kd->decrypt_key, op->src, op->dst, op->iv, op->len, rounds);
  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      kd = (aes_cbc_key_data_t *) cm->key_data[op->key_index];
      goto decrypt;
    }

  return n_ops;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
