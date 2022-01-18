/*
 * ipsec.c : IPSEC module functions
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

#include <sys/random.h>

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/udp/udp_local.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec_itf.h>

/* Flow cache is sized for 1 million flows with a load factor of .25.
 */
#define IPSEC4_OUT_SPD_DEFAULT_HASH_NUM_BUCKETS (1 << 22)

ipsec_main_t ipsec_main;
esp_async_post_next_t esp_encrypt_async_next;
esp_async_post_next_t esp_decrypt_async_next;

static clib_error_t *
ipsec_check_ah_support (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;

  if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    return clib_error_return (0, "unsupported none integ-alg");

  if (!vnet_crypto_is_set_handler (im->integ_algs[sa->integ_alg].alg))
    return clib_error_return (0, "No crypto engine support for %U",
			      format_ipsec_integ_alg, sa->integ_alg);

  return 0;
}

static clib_error_t *
ipsec_check_esp_support (ipsec_sa_t * sa)
{
  ipsec_main_t *im = &ipsec_main;

  if (IPSEC_INTEG_ALG_NONE != sa->integ_alg)
    {
      if (!vnet_crypto_is_set_handler (im->integ_algs[sa->integ_alg].alg))
	return clib_error_return (0, "No crypto engine support for %U",
				  format_ipsec_integ_alg, sa->integ_alg);
    }
  if (IPSEC_CRYPTO_ALG_NONE != sa->crypto_alg)
    {
      if (!vnet_crypto_is_set_handler (im->crypto_algs[sa->crypto_alg].alg))
	return clib_error_return (0, "No crypto engine support for %U",
				  format_ipsec_crypto_alg, sa->crypto_alg);
    }

  return (0);
}

clib_error_t *
ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index, u8 is_add)
{
  ipsec_ah_backend_t *ah =
    pool_elt_at_index (im->ah_backends, im->ah_current_backend);
  if (ah->add_del_sa_sess_cb)
    {
      clib_error_t *err = ah->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  ipsec_esp_backend_t *esp =
    pool_elt_at_index (im->esp_backends, im->esp_current_backend);
  if (esp->add_del_sa_sess_cb)
    {
      clib_error_t *err = esp->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  return 0;
}

clib_error_t *
ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa)
{
  clib_error_t *error = 0;

  if (PREDICT_FALSE (sa->protocol == IPSEC_PROTOCOL_AH))
    {
      ipsec_ah_backend_t *ah =
	pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      ASSERT (ah->check_support_cb);
      error = ah->check_support_cb (sa);
    }
  else
    {
      ipsec_esp_backend_t *esp =
	pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      ASSERT (esp->check_support_cb);
      error = esp->check_support_cb (sa);
    }
  return error;
}


static void
ipsec_add_node (vlib_main_t * vm, const char *node_name,
		const char *prev_node_name, u32 * out_node_index,
		u32 * out_next_index)
{
  vlib_node_t *prev_node, *node;
  prev_node = vlib_get_node_by_name (vm, (u8 *) prev_node_name);
  ASSERT (prev_node);
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  ASSERT (node);
  *out_node_index = node->index;
  *out_next_index = vlib_node_add_next (vm, prev_node->index, node->index);
}

void
ipsec_unregister_udp_port (u16 port)
{
  ipsec_main_t *im = &ipsec_main;
  u32 n_regs;
  uword *p;

  p = hash_get (im->udp_port_registrations, port);

  ASSERT (p);

  n_regs = p[0];

  if (0 == --n_regs)
    {
      udp_unregister_dst_port (vlib_get_main (), port, 1);
      hash_unset (im->udp_port_registrations, port);
    }
  else
    {
      hash_unset (im->udp_port_registrations, port);
      hash_set (im->udp_port_registrations, port, n_regs);
    }
}

void
ipsec_register_udp_port (u16 port)
{
  ipsec_main_t *im = &ipsec_main;
  u32 n_regs;
  uword *p;

  p = hash_get (im->udp_port_registrations, port);

  n_regs = (p ? p[0] : 0);

  if (0 == n_regs++)
    udp_register_dst_port (vlib_get_main (), port,
			   ipsec4_tun_input_node.index, 1);

  hash_unset (im->udp_port_registrations, port);
  hash_set (im->udp_port_registrations, port, n_regs);
}

u32
ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			   const char *name,
			   const char *ah4_encrypt_node_name,
			   const char *ah4_decrypt_node_name,
			   const char *ah6_encrypt_node_name,
			   const char *ah6_decrypt_node_name,
			   check_support_cb_t ah_check_support_cb,
			   add_del_sa_sess_cb_t ah_add_del_sa_sess_cb)
{
  ipsec_ah_backend_t *b;
  pool_get (im->ah_backends, b);
  b->name = format (0, "%s%c", name, 0);

  ipsec_add_node (vm, ah4_encrypt_node_name, "ipsec4-output-feature",
		  &b->ah4_encrypt_node_index, &b->ah4_encrypt_next_index);
  ipsec_add_node (vm, ah4_decrypt_node_name, "ipsec4-input-feature",
		  &b->ah4_decrypt_node_index, &b->ah4_decrypt_next_index);
  ipsec_add_node (vm, ah6_encrypt_node_name, "ipsec6-output-feature",
		  &b->ah6_encrypt_node_index, &b->ah6_encrypt_next_index);
  ipsec_add_node (vm, ah6_decrypt_node_name, "ipsec6-input-feature",
		  &b->ah6_decrypt_node_index, &b->ah6_decrypt_next_index);

  b->check_support_cb = ah_check_support_cb;
  b->add_del_sa_sess_cb = ah_add_del_sa_sess_cb;
  return b - im->ah_backends;
}

u32
ipsec_register_esp_backend (
  vlib_main_t *vm, ipsec_main_t *im, const char *name,
  const char *esp4_encrypt_node_name, const char *esp4_encrypt_node_tun_name,
  const char *esp4_decrypt_node_name, const char *esp4_decrypt_tun_node_name,
  const char *esp6_encrypt_node_name, const char *esp6_encrypt_node_tun_name,
  const char *esp6_decrypt_node_name, const char *esp6_decrypt_tun_node_name,
  const char *esp_mpls_encrypt_node_tun_name,
  check_support_cb_t esp_check_support_cb,
  add_del_sa_sess_cb_t esp_add_del_sa_sess_cb,
  enable_disable_cb_t enable_disable_cb)
{
  ipsec_esp_backend_t *b;

  pool_get (im->esp_backends, b);
  b->name = format (0, "%s%c", name, 0);

  ipsec_add_node (vm, esp4_encrypt_node_name, "ipsec4-output-feature",
		  &b->esp4_encrypt_node_index, &b->esp4_encrypt_next_index);
  ipsec_add_node (vm, esp4_decrypt_node_name, "ipsec4-input-feature",
		  &b->esp4_decrypt_node_index, &b->esp4_decrypt_next_index);
  ipsec_add_node (vm, esp6_encrypt_node_name, "ipsec6-output-feature",
		  &b->esp6_encrypt_node_index, &b->esp6_encrypt_next_index);
  ipsec_add_node (vm, esp6_decrypt_node_name, "ipsec6-input-feature",
		  &b->esp6_decrypt_node_index, &b->esp6_decrypt_next_index);
  ipsec_add_node (vm, esp4_decrypt_tun_node_name, "ipsec4-tun-input",
		  &b->esp4_decrypt_tun_node_index,
		  &b->esp4_decrypt_tun_next_index);
  ipsec_add_node (vm, esp6_decrypt_tun_node_name, "ipsec6-tun-input",
		  &b->esp6_decrypt_tun_node_index,
		  &b->esp6_decrypt_tun_next_index);

  b->esp6_encrypt_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) esp6_encrypt_node_tun_name)->index;
  b->esp_mpls_encrypt_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) esp_mpls_encrypt_node_tun_name)->index;
  b->esp4_encrypt_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) esp4_encrypt_node_tun_name)->index;

  b->check_support_cb = esp_check_support_cb;
  b->add_del_sa_sess_cb = esp_add_del_sa_sess_cb;
  b->enable_disable_cb = enable_disable_cb;

  return b - im->esp_backends;
}

clib_error_t *
ipsec_rsc_in_use (ipsec_main_t * im)
{
  /* return an error is crypto resource are in use */
  if (pool_elts (ipsec_sa_pool) > 0)
    return clib_error_return (0, "%d SA entries configured",
			      pool_elts (ipsec_sa_pool));
  if (ipsec_itf_count () > 0)
    return clib_error_return (0, "%d IPSec interface configured",
			      ipsec_itf_count ());

  return (NULL);
}

int
ipsec_select_ah_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (ipsec_rsc_in_use (im))
    return VNET_API_ERROR_RSRC_IN_USE;

  if (pool_is_free_index (im->ah_backends, backend_idx))
    return VNET_API_ERROR_INVALID_VALUE;

  ipsec_ah_backend_t *b = pool_elt_at_index (im->ah_backends, backend_idx);
  im->ah_current_backend = backend_idx;
  im->ah4_encrypt_node_index = b->ah4_encrypt_node_index;
  im->ah4_decrypt_node_index = b->ah4_decrypt_node_index;
  im->ah4_encrypt_next_index = b->ah4_encrypt_next_index;
  im->ah4_decrypt_next_index = b->ah4_decrypt_next_index;
  im->ah6_encrypt_node_index = b->ah6_encrypt_node_index;
  im->ah6_decrypt_node_index = b->ah6_decrypt_node_index;
  im->ah6_encrypt_next_index = b->ah6_encrypt_next_index;
  im->ah6_decrypt_next_index = b->ah6_decrypt_next_index;

  return 0;
}

int
ipsec_select_esp_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (ipsec_rsc_in_use (im))
    return VNET_API_ERROR_RSRC_IN_USE;

  if (pool_is_free_index (im->esp_backends, backend_idx))
    return VNET_API_ERROR_INVALID_VALUE;

  /* disable current backend */
  if (im->esp_current_backend != ~0)
    {
      ipsec_esp_backend_t *cb = pool_elt_at_index (im->esp_backends,
						   im->esp_current_backend);
      if (cb->enable_disable_cb)
	{
	  if ((cb->enable_disable_cb) (0) != 0)
	    return -1;
	}
    }

  ipsec_esp_backend_t *b = pool_elt_at_index (im->esp_backends, backend_idx);
  im->esp_current_backend = backend_idx;
  im->esp4_encrypt_node_index = b->esp4_encrypt_node_index;
  im->esp4_decrypt_node_index = b->esp4_decrypt_node_index;
  im->esp4_encrypt_next_index = b->esp4_encrypt_next_index;
  im->esp4_decrypt_next_index = b->esp4_decrypt_next_index;
  im->esp6_encrypt_node_index = b->esp6_encrypt_node_index;
  im->esp6_decrypt_node_index = b->esp6_decrypt_node_index;
  im->esp6_encrypt_next_index = b->esp6_encrypt_next_index;
  im->esp6_decrypt_next_index = b->esp6_decrypt_next_index;
  im->esp4_decrypt_tun_node_index = b->esp4_decrypt_tun_node_index;
  im->esp4_decrypt_tun_next_index = b->esp4_decrypt_tun_next_index;
  im->esp6_decrypt_tun_node_index = b->esp6_decrypt_tun_node_index;
  im->esp6_decrypt_tun_next_index = b->esp6_decrypt_tun_next_index;
  im->esp4_encrypt_tun_node_index = b->esp4_encrypt_tun_node_index;
  im->esp6_encrypt_tun_node_index = b->esp6_encrypt_tun_node_index;
  im->esp_mpls_encrypt_tun_node_index = b->esp_mpls_encrypt_tun_node_index;

  if (b->enable_disable_cb)
    {
      if ((b->enable_disable_cb) (1) != 0)
	return -1;
    }
  return 0;
}

void
ipsec_set_async_mode (u32 is_enabled)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa;

  vnet_crypto_request_async_mode (is_enabled);

  im->async_mode = is_enabled;

  /* change SA crypto op data */
  pool_foreach (sa, ipsec_sa_pool)
    {
      sa->crypto_op_data =
	(is_enabled ? sa->async_op_data.data : sa->sync_op_data.data);
    }
}

static void
crypto_engine_backend_register_post_node (vlib_main_t * vm)
{
  esp_async_post_next_t *eit;
  esp_async_post_next_t *dit;

  eit = &esp_encrypt_async_next;
  eit->esp4_post_next =
    vnet_crypto_register_post_node (vm, "esp4-encrypt-post");
  eit->esp6_post_next =
    vnet_crypto_register_post_node (vm, "esp6-encrypt-post");
  eit->esp4_tun_post_next =
    vnet_crypto_register_post_node (vm, "esp4-encrypt-tun-post");
  eit->esp6_tun_post_next =
    vnet_crypto_register_post_node (vm, "esp6-encrypt-tun-post");
  eit->esp_mpls_tun_post_next =
    vnet_crypto_register_post_node (vm, "esp-mpls-encrypt-tun-post");

  dit = &esp_decrypt_async_next;
  dit->esp4_post_next =
    vnet_crypto_register_post_node (vm, "esp4-decrypt-post");
  dit->esp6_post_next =
    vnet_crypto_register_post_node (vm, "esp6-decrypt-post");
  dit->esp4_tun_post_next =
    vnet_crypto_register_post_node (vm, "esp4-decrypt-tun-post");
  dit->esp6_tun_post_next =
    vnet_crypto_register_post_node (vm, "esp6-decrypt-tun-post");
}

static clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  clib_error_t *error;
  ipsec_main_t *im = &ipsec_main;
  ipsec_main_crypto_alg_t *a;
  struct
  {
    u64 initstate;
    u64 initseq;
  } *rand = 0;

  /* Backend registration requires the feature arcs to be set up */
  if ((error = vlib_call_init_function (vm, vnet_feature_init)))
    return (error);

  im->vnet_main = vnet_get_main ();
  im->vlib_main = vm;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  ASSERT (node);
  im->error_drop_node_index = node->index;

  im->ah_current_backend = ~0;
  im->esp_current_backend = ~0;

  u32 idx = ipsec_register_ah_backend (vm, im, "crypto engine backend",
				       "ah4-encrypt",
				       "ah4-decrypt",
				       "ah6-encrypt",
				       "ah6-decrypt",
				       ipsec_check_ah_support,
				       NULL);

  im->ah_default_backend = idx;
  int rv = ipsec_select_ah_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  idx = ipsec_register_esp_backend (
    vm, im, "crypto engine backend", "esp4-encrypt", "esp4-encrypt-tun",
    "esp4-decrypt", "esp4-decrypt-tun", "esp6-encrypt", "esp6-encrypt-tun",
    "esp6-decrypt", "esp6-decrypt-tun", "esp-mpls-encrypt-tun",
    ipsec_check_esp_support, NULL, crypto_dispatch_enable_disable);
  im->esp_default_backend = idx;

  rv = ipsec_select_esp_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  if ((error = vlib_call_init_function (vm, ipsec_cli_init)))
    return error;

  vec_validate (im->crypto_algs, IPSEC_CRYPTO_N_ALG - 1);

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_NONE;
  a->enc_op_id = VNET_CRYPTO_OP_NONE;
  a->dec_op_id = VNET_CRYPTO_OP_NONE;
  a->alg = VNET_CRYPTO_ALG_NONE;
  a->iv_size = 0;
  a->block_align = 1;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_DES_CBC;
  a->enc_op_id = VNET_CRYPTO_OP_DES_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_DES_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_DES_CBC;
  a->iv_size = a->block_align = 8;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_3DES_CBC;
  a->enc_op_id = VNET_CRYPTO_OP_3DES_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_3DES_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_3DES_CBC;
  a->iv_size = a->block_align = 8;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_128;
  a->enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_128_CBC;
  a->iv_size = a->block_align = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_192;
  a->enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_192_CBC;
  a->iv_size = a->block_align = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CBC_256;
  a->enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_256_CBC;
  a->iv_size = a->block_align = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CTR_128;
  a->enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_128_CTR;
  a->iv_size = 8;
  a->block_align = 1;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CTR_192;
  a->enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_192_CTR;
  a->iv_size = 8;
  a->block_align = 1;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_CTR_256;
  a->enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_256_CTR;
  a->iv_size = 8;
  a->block_align = 1;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_128;
  a->enc_op_id = VNET_CRYPTO_OP_AES_128_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_128_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_128_GCM;
  a->iv_size = 8;
  a->block_align = 1;
  a->icv_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_192;
  a->enc_op_id = VNET_CRYPTO_OP_AES_192_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_192_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_192_GCM;
  a->iv_size = 8;
  a->block_align = 1;
  a->icv_size = 16;

  a = im->crypto_algs + IPSEC_CRYPTO_ALG_AES_GCM_256;
  a->enc_op_id = VNET_CRYPTO_OP_AES_256_GCM_ENC;
  a->dec_op_id = VNET_CRYPTO_OP_AES_256_GCM_DEC;
  a->alg = VNET_CRYPTO_ALG_AES_256_GCM;
  a->iv_size = 8;
  a->block_align = 1;
  a->icv_size = 16;

  vec_validate (im->integ_algs, IPSEC_INTEG_N_ALG - 1);
  ipsec_main_integ_alg_t *i;

  i = &im->integ_algs[IPSEC_INTEG_ALG_MD5_96];
  i->op_id = VNET_CRYPTO_OP_MD5_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_MD5;
  i->icv_size = 12;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->op_id = VNET_CRYPTO_OP_SHA1_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA1;
  i->icv_size = 12;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->op_id = VNET_CRYPTO_OP_SHA1_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA256;
  i->icv_size = 12;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->op_id = VNET_CRYPTO_OP_SHA256_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA256;
  i->icv_size = 16;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->op_id = VNET_CRYPTO_OP_SHA384_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA384;
  i->icv_size = 24;

  i = &im->integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->op_id = VNET_CRYPTO_OP_SHA512_HMAC;
  i->alg = VNET_CRYPTO_ALG_HMAC_SHA512;
  i->icv_size = 32;

  vec_validate_aligned (im->ptd, vlib_num_workers (), CLIB_CACHE_LINE_BYTES);
  vec_validate (rand, vec_len (im->ptd));
  if (getrandom (rand, vec_bytes (rand), 0) != vec_bytes (rand))
    return clib_error_return_unix_fatal (0,
					 "getrandom() failed to get entropy");
  vec_foreach_index (idx, im->ptd)
    clib_pcg64i_srandom_r (&vec_elt (im->ptd, idx).iv_prng,
			   vec_elt (rand, idx).initstate,
			   vec_elt (rand, idx).initseq);
  vec_free (rand);

  im->async_mode = 0;
  crypto_engine_backend_register_post_node (vm);

  im->ipsec4_out_spd_hash_tbl = NULL;
  im->flow_cache_flag = 0;
  im->ipsec4_out_spd_flow_cache_entries = 0;
  im->epoch_count = 0;
  im->ipsec4_out_spd_hash_num_buckets =
    IPSEC4_OUT_SPD_DEFAULT_HASH_NUM_BUCKETS;

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_init);

static clib_error_t *
ipsec_config (vlib_main_t *vm, unformat_input_t *input)
{
  ipsec_main_t *im = &ipsec_main;
  unformat_input_t sub_input;
  u32 ipsec4_out_spd_hash_num_buckets;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ipv4-outbound-spd-flow-cache on"))
	im->flow_cache_flag = 1;
      else if (unformat (input, "ipv4-outbound-spd-flow-cache off"))
	im->flow_cache_flag = 0;
      else if (unformat (input, "ipv4-outbound-spd-hash-buckets %d",
			 &ipsec4_out_spd_hash_num_buckets))
	{
	  /* Size of hash is power of 2 >= number of buckets */
	  im->ipsec4_out_spd_hash_num_buckets =
	    1ULL << max_log2 (ipsec4_out_spd_hash_num_buckets);
	}
      else if (unformat (input, "ip4 %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  uword table_size = ~0;
	  u32 n_buckets = ~0;

	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "num-buckets %u", &n_buckets))
		;
	      else
		return clib_error_return (0, "unknown input `%U'",
					  format_unformat_error, &sub_input);
	    }

	  ipsec_tun_table_init (AF_IP4, table_size, n_buckets);
	}
      else if (unformat (input, "ip6 %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  uword table_size = ~0;
	  u32 n_buckets = ~0;

	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "num-buckets %u", &n_buckets))
		;
	      else
		return clib_error_return (0, "unknown input `%U'",
					  format_unformat_error, &sub_input);
	    }

	  ipsec_tun_table_init (AF_IP6, table_size, n_buckets);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  if (im->flow_cache_flag)
    {
      vec_add2 (im->ipsec4_out_spd_hash_tbl, im->ipsec4_out_spd_hash_tbl,
		im->ipsec4_out_spd_hash_num_buckets);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (ipsec_config, "ipsec");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
