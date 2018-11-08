/*
 * init.c : ipsecmb common code
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ipsecmb/ipsecmb.h>
ipsecmb_main_t ipsecmb_main;

int
sa_expand_keys (u32 sa_index)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_sa_t *sa = pool_elt_at_index (ipsec_main.sad, sa_index);
  ipsecmb_sa_t *samb = pool_elt_at_index (imbm->sad, sa_index);
  if (sa->crypto_key_len > 0)
    {
      const keyexp_t keyexp_fn = imbm->crypto_algs[sa->crypto_alg].keyexp_fn;
      keyexp_fn (sa->crypto_key, samb->aes_enc_key_expanded,
		 samb->aes_dec_key_expanded);
    }
  if (sa->integ_key_len > 0)
    {
      const u8 block_size = imbm->integ_algs[sa->integ_alg].block_size;
      const hash_one_block_t hash_one_block_fn =
	imbm->integ_algs[sa->integ_alg].hash_one_block_fn;
      u8 buf[block_size];
      int i = 0;
      if (sa->integ_key_len > block_size)
	{
	  return VNET_API_ERROR_SYSCALL_ERROR_1;	// FIXME use correct value
	}
      memset (buf, 0x36, sizeof (buf));
      for (i = 0; i < sa->integ_key_len; i++)
	{
	  buf[i] ^= sa->integ_key[i];
	}
      hash_one_block_fn (buf, samb->ipad_hash);

      memset (buf, 0x5c, sizeof (buf));
      for (i = 0; i < sa->integ_key_len; i++)
	{
	  buf[i] ^= sa->integ_key[i];
	}
      hash_one_block_fn (buf, samb->opad_hash);
    }
  return 0;
}

static clib_error_t *
ipsecmb_add_del_sa_session (u32 sa_index, u8 is_add)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  if (is_add)
    {
      ipsecmb_sa_t *samb = NULL;
      pool_get (imbm->sad, samb);
      ASSERT (samb == pool_elt_at_index (imbm->sad, sa_index));
      sa_expand_keys (sa_index);
    }
  else
    {
      pool_put_index (imbm->sad, sa_index);
    }
  return 0;
}

clib_error_t *
ipsecmb_check_esp_support (ipsec_sa_t * sa)
{
  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_NONE:
      break;
    case IPSEC_CRYPTO_ALG_DES_CBC:
    case IPSEC_CRYPTO_ALG_3DES_CBC:
      return clib_error_return (0, "unsupported (3)des crypto-alg");
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
      break;
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      return clib_error_return (0, "unsupported aes-ctr crypto-alg");
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
    case IPSEC_CRYPTO_ALG_AES_GCM_192:
    case IPSEC_CRYPTO_ALG_AES_GCM_256:
      return clib_error_return (0, "unsupported aes-gcm crypto-alg");
    case IPSEC_CRYPTO_N_ALG:
      return clib_error_return (0, "invalid crypto-alg");
    }

  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_NONE:
      return clib_error_return (0, "unsupported none integ-alg");
    case IPSEC_INTEG_ALG_MD5_96:
      return clib_error_return (0, "unsupported md5 integ-alg");
    case IPSEC_INTEG_ALG_SHA1_96:
    case IPSEC_INTEG_ALG_SHA_256_96:
    case IPSEC_INTEG_ALG_SHA_256_128:
    case IPSEC_INTEG_ALG_SHA_384_192:
    case IPSEC_INTEG_ALG_SHA_512_256:
      break;
    case IPSEC_INTEG_N_ALG:
      return clib_error_return (0, "invalid integ-alg");
    }
  return 0;
}

clib_error_t *
ipsecmb_check_ah_support (ipsec_sa_t * sa)
{
  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_NONE:
      return clib_error_return (0, "unsupported none integ-alg");
    case IPSEC_INTEG_ALG_MD5_96:
      return clib_error_return (0, "unsupported md5 integ-alg");
    case IPSEC_INTEG_ALG_SHA1_96:
    case IPSEC_INTEG_ALG_SHA_256_96:
    case IPSEC_INTEG_ALG_SHA_256_128:
    case IPSEC_INTEG_ALG_SHA_384_192:
    case IPSEC_INTEG_ALG_SHA_512_256:
      break;
    case IPSEC_INTEG_N_ALG:
      return clib_error_return (0, "invalid integ-alg");
    }
  return 0;
}

static clib_error_t *
ipsecmb_init (vlib_main_t * vm)
{
  ipsecmb_main_t *imbm = &ipsecmb_main;
  imbm->dev_urandom_fd = open ("/dev/urandom", O_RDONLY);
  if (!imbm->dev_urandom_fd)
    {
      return clib_error_return_unix_fatal (0,
					   "Can't open /dev/urandom for read");
    }

  vlib_thread_main_t *tm = vlib_get_thread_main ();

  imbm->crypto_algs = NULL;
  imbm->integ_algs = NULL;

  vec_validate (imbm->crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  vec_validate (imbm->integ_algs, IPSEC_INTEG_N_ALG - 1);
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].block_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].block_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].block_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].block_size = 8;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].block_size = 8;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].iv_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].iv_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].iv_size = 16;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].iv_size = 8;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].iv_size = 8;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].cipher_mode = CBC;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].cipher_mode = CBC;
  imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].cipher_mode = CBC;

  ipsecmb_integ_alg_t *i;
  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->hash_alg = SHA1;
  i->block_size = SHA1_BLOCK_SIZE;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->hash_alg = SHA_256;
  i->block_size = SHA_256_BLOCK_SIZE;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->hash_alg = SHA_256;
  i->block_size = SHA_256_BLOCK_SIZE;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->hash_alg = SHA_384;
  i->block_size = SHA_384_BLOCK_SIZE;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->hash_alg = SHA_512;
  i->block_size = SHA_512_BLOCK_SIZE;

  vec_validate (imbm->mb_mgr, tm->n_vlib_mains - 1);
  MB_MGR **mgr;
#define __set_funcs(arch)                                               \
  do                                                                    \
    {                                                                   \
      imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].keyexp_fn =       \
          aes_keyexp_128_##arch;                                        \
      imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].keyexp_fn =       \
          aes_keyexp_192_##arch;                                        \
      imbm->crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].keyexp_fn =       \
          aes_keyexp_256_##arch;                                        \
      imbm->integ_algs[IPSEC_INTEG_ALG_SHA1_96].hash_one_block_fn =     \
          sha1_one_block_##arch;                                        \
      imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_96].hash_one_block_fn =  \
          sha256_one_block_##arch;                                      \
      imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_128].hash_one_block_fn = \
          sha256_one_block_##arch;                                      \
      imbm->integ_algs[IPSEC_INTEG_ALG_SHA_384_192].hash_one_block_fn = \
          sha384_one_block_##arch;                                      \
      imbm->integ_algs[IPSEC_INTEG_ALG_SHA_512_256].hash_one_block_fn = \
          sha512_one_block_##arch;                                      \
    }                                                                   \
  while (0);

  if (clib_cpu_supports_avx512f ())
    {
      __set_funcs (avx512);
      vec_foreach (mgr, imbm->mb_mgr)
      {
	*mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx512 (*mgr);
      }
    }
  else if (clib_cpu_supports_avx2 ())
    {
      __set_funcs (avx2);
      vec_foreach (mgr, imbm->mb_mgr)
      {
	*mgr = alloc_mb_mgr (0);
	init_mb_mgr_avx2 (*mgr);
      }
    }
  else
    {
      __set_funcs (sse);
      vec_foreach (mgr, imbm->mb_mgr)
      {
	*mgr = alloc_mb_mgr (0);
	init_mb_mgr_sse (*mgr);
      }
    }
#undef __set_funcs


  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->hash_output_length = 12;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->hash_output_length = 12;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->hash_output_length = 16;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->hash_output_length = 24;

  i = &imbm->integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->hash_output_length = 32;

  vec_validate (imbm->per_thread_data, tm->n_vlib_mains - 1);

  return 0;
}

VLIB_INIT_FUNCTION (ipsecmb_init);

static uword
ipsecmb_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_register_ah_backend (vm, im, "ipsecmb backend",
			     "ah4-encrypt-ipsecmb",
			     "ah4-decrypt-ipsecmb",
			     "ah6-encrypt-ipsecmb",
			     "ah6-decrypt-ipsecmb",
			     ipsecmb_check_ah_support,
			     ipsecmb_add_del_sa_session);

  ipsec_register_esp_backend (vm, im, "ipsecmb backend",
			      "esp4-encrypt-ipsecmb",
			      "esp4-decrypt-ipsecmb",
			      "esp6-encrypt-ipsecmb",
			      "esp6-decrypt-ipsecmb",
			      ipsecmb_check_esp_support,
			      ipsecmb_add_del_sa_session);

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsecmb_process_node, static) = {
    .function = ipsecmb_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ipsecmb-process",
    .process_log2_n_stack_bytes = 17,
};

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "IPsecMB plugin",
    .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
