/*
 * ipsecmb.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <intel-ipsec-mb.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/cpu.h>

typedef struct
{
  MB_MGR *mgr;
} ipsecmb_per_thread_data_t;

typedef struct ipsecmb_main_t_
{
  ipsecmb_per_thread_data_t *per_thread_data;
} ipsecmb_main_t;

static ipsecmb_main_t ipsecmb_main;

#define foreach_ipsecmb_hmac_op                                \
  _(SHA1, SHA1, sha1)                                          \
  _(SHA256, SHA_256, sha256)                                   \
  _(SHA384, SHA_384, sha384)                                   \
  _(SHA512, SHA_512, sha512)

always_inline void
hash_expand_keys (const MB_MGR * mgr,
		  const u8 * key,
		  u32 length,
		  u8 block_size,
		  u8 ipad[256], u8 opad[256], hash_one_block_t fn)
{
  u8 buf[block_size];
  int i = 0;

  if (length > block_size)
    {
      return;
    }

  memset (buf, 0x36, sizeof (buf));
  for (i = 0; i < length; i++)
    {
      buf[i] ^= key[i];
    }
  fn (buf, ipad);

  memset (buf, 0x5c, sizeof (buf));

  for (i = 0; i < length; i++)
    {
      buf[i] ^= key[i];
    }
  fn (buf, opad);
}

always_inline void
ipsecmb_postprocess_job (JOB_AES_HMAC * job, u32 * n_fail)
{
  vnet_crypto_op_t *op = job->user_data;

  if (STS_COMPLETED != job->status)
    {
      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      *n_fail = *n_fail + 1;
    }
  else
    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
}

static_always_inline u32
ipsecmb_ops_hmac_inline (vlib_main_t * vm,
			 vnet_crypto_op_t * ops[],
			 u32 n_ops,
			 u32 block_size,
			 hash_one_block_t fn, JOB_HASH_ALG alg)
{
  ipsecmb_per_thread_data_t *ptd;
  ipsecmb_main_t *imbm;
  JOB_AES_HMAC *job;
  u32 i, n_fail = 0;

  imbm = &ipsecmb_main;
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u8 ipad[256] __attribute__ ((aligned (16)));
      u8 opad[256] __attribute__ ((aligned (16)));

      hash_expand_keys (ptd->mgr, op->key, op->key_len,
			SHA1_BLOCK_SIZE,
			ipad, opad, ptd->mgr->sha1_one_block);

      job = IMB_GET_NEXT_JOB (ptd->mgr);

      job->src = op->src;
      job->dst = op->dst;
      job->hash_start_src_offset_in_bytes = 0;
      job->msg_len_to_hash_in_bytes = op->len;
      job->hash_alg = alg;	// IPSEC_MB_CRYPT_ALGO(op->op);
      job->auth_tag_output_len_in_bytes = op->digest_len;
      job->auth_tag_output = op->digest;

      job->cipher_mode = NULL_CIPHER;
      job->cipher_direction = DECRYPT;
      job->chain_order = HASH_CIPHER;

      job->aes_key_len_in_bytes = op->key_len;

      job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
      job->u.HMAC._hashed_auth_key_xor_opad = opad;
      job->user_data = op;

      job = IMB_SUBMIT_JOB (ptd->mgr);

      if (job)
	ipsecmb_postprocess_job (job, &n_fail);
    }

  // flush all remaining jobs
  while ((job = IMB_FLUSH_JOB (ptd->mgr)))
    {
      ipsecmb_postprocess_job (job, &n_fail);
    }

  return n_ops - n_fail;
}

#define _(a, b, c)                                                      \
static_always_inline u32                                                \
ipsecmb_ops_hmac_##a (vlib_main_t * vm,                                 \
                      vnet_crypto_op_t * ops[],                         \
                      u32 n_ops)                                        \
{                                                                       \
  ipsecmb_per_thread_data_t *ptd;                                       \
  ipsecmb_main_t *imbm;                                                 \
                                                                        \
  imbm = &ipsecmb_main;                                                 \
  ptd = vec_elt_at_index (imbm->per_thread_data, vm->thread_index);     \
                                                                        \
  return ipsecmb_ops_hmac_inline (vm, ops, n_ops,                       \
                                  b##_BLOCK_SIZE,                       \
                                  ptd->mgr->c##_one_block,              \
                                  b);                                   \
  }
foreach_ipsecmb_hmac_op;
#undef _

static clib_error_t *
crypto_ipsecmb_init (vlib_main_t * vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsecmb_per_thread_data_t *ptd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
  u32 eidx;

  if ((error = vlib_call_init_function (vm, vnet_crypto_init)))
    return error;

  eidx = vnet_crypto_register_engine (vm, "ipsecmb", 80,
				      "Intel IPSEC multi-buffer");

  vec_validate (imbm->per_thread_data, tm->n_vlib_mains - 1);

  if (clib_cpu_supports_avx512f ())
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx512 (ptd->mgr);
      }
    }
  else if (clib_cpu_supports_avx2 ())
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx2 (ptd->mgr);
      }
    }
  else
    {
      vec_foreach (ptd, imbm->per_thread_data)
      {
	ptd->mgr = alloc_mb_mgr (0);
	init_mb_mgr_sse (ptd->mgr);
      }
    }

#define _(a, b, c)                                                       \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
                                    ipsecmb_ops_hmac_##a);               \

  foreach_ipsecmb_hmac_op;
#undef _

  return 0;
}

VLIB_INIT_FUNCTION (crypto_ipsecmb_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Intel IPSEC multi-buffer",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
