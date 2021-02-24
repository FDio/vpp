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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/udp/udp_local.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>

ipsec_main_t ipsec_main;
esp_async_post_next_t esp_encrypt_async_next;
esp_async_post_next_t esp_decrypt_async_next;

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

static clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_main_crypto_alg_t *a;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

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

  im->async_mode = 0;
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

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
