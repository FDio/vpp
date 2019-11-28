/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>
#include <rte_crypto.h>
#include <rte_cryptodev_pmd.h>
#include <rte_bus_vdev.h>
#include <rte_config.h>

#include "cryptodev.h"

#define IV_OFF (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define MAX_IV_SIZE 16

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN */
#define foreach_vnet_cipher_crypto_conversion \
  _(AES_128_CBC, CIPHER, AES_CBC, 16) \
  _(AES_192_CBC, CIPHER, AES_CBC, 16) \
  _(AES_256_CBC, CIPHER, AES_CBC, 16) \
  _(AES_128_CTR, CIPHER, AES_CTR, 16) \
  _(AES_192_CTR, CIPHER, AES_CTR, 16) \
  _(AES_256_CTR, CIPHER, AES_CTR, 16) \
  _(3DES_CBC, CIPHER, 3DES_CBC, 8)

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN */
#define foreach_vnet_aead_crypto_conversion \
  _(AES_128_GCM, AEAD, AES_GCM, 12) \
  _(AES_192_GCM, AEAD, AES_GCM, 12) \
  _(AES_256_GCM, AEAD, AES_GCM, 12)

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, DIGEST_LEN */
#define foreach_vnet_hmac_crypto_conversion \
  _(SHA1,   AUTH, SHA1_HMAC,   20) \
  _(SHA224, AUTH, SHA224_HMAC, 28) \
  _(SHA256, AUTH, SHA256_HMAC, 32) \
  _(SHA384, AUTH, SHA384_HMAC, 48) \
  _(SHA512, AUTH, SHA512_HMAC, 64)

#define foreach_vnet_crypto_status_conversion \
  _(WORK_IN_PROGRESS, NOT_PROCESSED) \
  _(COMPLETED, SUCCESS) \
  _(FAIL_BAD_HMAC, AUTH_FAILED)

typedef struct
{
  rte_iova_t src;
  rte_iova_t dst;
  rte_iova_t digest;
  rte_iova_t aad;
} cryptodev_iova_t;

typedef struct
{
  struct rte_crypto_op op;
  struct rte_crypto_sym_op sop;
  u8 iv[16];
  u8 aad[16];
  struct rte_mbuf msrc;
  struct rte_mbuf mdst;
  vnet_crypto_op_t *vop;
} cryptodev_op_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cryptodev_op_t *crypto_op_pool;
  u8 cryptodev_id;
  u8 cryptodev_q;
  u32 inflight;
  u16 cur_op_idx;
  u32 enc_counter;
  u32 dec_counter;
  struct rte_crypto_op **ops;
} cryptodev_engine_thread_t;

typedef enum
{
        DIR_OUT = 0,    /**< Need to be encrypted */
        DIR_IN        /**< Need to be decrypted */
} cryptodev_encryption_dir_t;

typedef struct
{
  struct rte_cryptodev_sym_session *keys[2];
  u32 iv_len;
  u32 aad_len;
  u32 digest_len;
} key_info_t;

typedef struct
{
  u32 dev_id;
  u32 q_id;
  char *desc;
} cryptodev_inst_t;

typedef struct
{
  struct rte_mempool *sess_pool;
  struct rte_mempool *sess_priv_pool;
} cryptodev_numa_data_t;

typedef struct
{
  cryptodev_numa_data_t *per_numa_data;
  key_info_t *keys;
  cryptodev_engine_thread_t *per_thread_data;
  cryptodev_inst_t *cryptodev_inst;
  clib_bitmap_t *active_cdev_inst_mask;
  clib_spinlock_t tlock;
} cryptodev_main_t;

cryptodev_main_t cryptodev_main;

/**
 * @return 1: out-of-place operation
 * @return 0: in-place operation
 * @return <0: invalid buffer
 */
typedef int (*_pre_iova_compute) (vlib_main_t * vm,
    vnet_crypto_op_t *vop, cryptodev_iova_t *iova);

typedef int (*_need_key_update)(key_info_t *key, vnet_crypto_op_t *vop);

typedef void (*_translate_vop) (cryptodev_op_t *cop,
    vnet_crypto_op_t *vop, struct rte_cryptodev_sym_session *sess,
    u16 iv_len, cryptodev_iova_t *iova);

static_always_inline int
cipher_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova);

static_always_inline int
cipher_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop);

static_always_inline void
cipher_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                         struct rte_cryptodev_sym_session *sess,
                         u16 iv_len, cryptodev_iova_t *iova);

static_always_inline int
aead_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova);

static_always_inline int
aead_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop);

static_always_inline void
aead_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                         struct rte_cryptodev_sym_session *sess,
                         u16 iv_len, cryptodev_iova_t *iova);
static_always_inline int
auth_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova);

static_always_inline int
auth_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop);

static_always_inline void
auth_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                         struct rte_cryptodev_sym_session *sess,
                         u16 iv_len, cryptodev_iova_t *iova);

static int
prepare_cipher_xform (struct rte_crypto_sym_xform *xform,
                      u32 direction, const vnet_crypto_key_t * key, u32 algo,
                      u32 iv_len)
{
  struct rte_crypto_cipher_xform *cipher_xform = &xform->cipher;

  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

  cipher_xform->algo = algo;
  cipher_xform->op = (direction == DIR_OUT) ?
    RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;
  cipher_xform->key.data = key->data;
  cipher_xform->key.length = vec_len (key->data);
  cipher_xform->iv.length = iv_len;
  cipher_xform->iv.offset = IV_OFF;
  return 0;
}

static int
prepare_auth_xform(struct rte_crypto_sym_xform * xform,
                   u32 direction, const vnet_crypto_key_t * key,
                   u32 algo, u32 digest_len)
{
  struct rte_crypto_auth_xform *auth_xform = &xform->auth;
  memset(xform, 0, sizeof(*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  auth_xform->algo = algo;
  auth_xform->op = (direction == DIR_OUT) ?
    RTE_CRYPTO_AUTH_OP_GENERATE : RTE_CRYPTO_AUTH_OP_VERIFY;
  auth_xform->digest_length = digest_len;
  auth_xform->key.data = key->data;
  auth_xform->key.length = vec_len (key->data);
  return 0;
}

static int
prepare_aead_xform(struct rte_crypto_sym_xform * xform,
                  u32 direction, const vnet_crypto_key_t * key, u32 algo,
                  u32 iv_len, u32 aad_len, u32 digest_len)
{
  struct rte_crypto_aead_xform *aead_xform = &xform->aead;
  memset(xform, 0, sizeof(*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;

  aead_xform->algo = algo;
  aead_xform->op = (direction ==DIR_OUT) ?
                  RTE_CRYPTO_AEAD_OP_ENCRYPT :
                  RTE_CRYPTO_AEAD_OP_DECRYPT;
  aead_xform->aad_length = aad_len;
  aead_xform->digest_length = digest_len;
  aead_xform->iv.offset = IV_OFF;
  aead_xform->iv.length = iv_len;
  aead_xform->key.data = key->data;
  aead_xform->key.length = vec_len(key->data);

  return 0;
}

/**
 * lookup the vnet_crypto_alg_t type and transform to dpdk xform type
 *
 *  @param vnet_alg: vnet_crypto_alg_t algo
 *  @param xform_type: the transformed xform type
 *
 *  @return: rte_crypto_cipher_algorithm / rte_crypto_auth_algorithm /
 *      rte_crypto_aead_algorithm enum type
 */
static int
transform_vnet_crypto_type (vnet_crypto_alg_t vnet_alg, u32 *cryptodev_algo,
                            enum rte_crypto_sym_xform_type *xform_type,
                            u32 *iv_len, u32 *digest_len)
{
  switch (vnet_alg)
    {
#define _(v, t, c, i) \
    case VNET_CRYPTO_ALG_##v: \
      *xform_type = RTE_CRYPTO_SYM_XFORM_##t; \
      *cryptodev_algo = RTE_CRYPTO_##t##_##c; \
      *iv_len = i; \
      return 0;

foreach_vnet_cipher_crypto_conversion
foreach_vnet_aead_crypto_conversion
#undef _

#define _(v, t, c, d) \
    case VNET_CRYPTO_ALG_HMAC_##v: \
      *xform_type = RTE_CRYPTO_SYM_XFORM_##t; \
      *cryptodev_algo = RTE_CRYPTO_##t##_##c; \
      if (*digest_len == ~0) \
        *digest_len = d; \
      return 0;

foreach_vnet_hmac_crypto_conversion
#undef _
    default:
      *xform_type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED;
      return -1;
    }
}

  /**
 * Return a created session by parsing vnet_crypto_key_t, REMEMBER:
 * - check key->next for chained op
 * - every device type should have a sess priv data set-up, unless the device does not support the alg
 */
static int
cryptodev_cipher_session_create (vnet_crypto_key_t * const key,
                          struct rte_mempool *sess_pool,
                          struct rte_mempool *sess_priv_pool,
                          key_info_t * session_pair,
                          u32 iv_len,
                          u32 cipher_cryptodev_algo,
                          enum rte_crypto_sym_xform_type xform_type)
{
  struct rte_crypto_sym_xform cipher_xform;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  int ret;
  uint8_t dev_id = 0;

  prepare_cipher_xform (&cipher_xform, DIR_OUT, key,
                       cipher_cryptodev_algo, iv_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
  {
    dev_id = dev_inst->dev_id;
    ret =
      rte_cryptodev_sym_session_init (dev_id, session_pair->keys[0], &cipher_xform,
                                     sess_priv_pool);
    if (ret < 0)
      return ret;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    ret =
      rte_cryptodev_sym_session_init (dev_id, session_pair->keys[1], &cipher_xform,
                                      sess_priv_pool);
    if (ret < 0)
      return ret;
  }

  session_pair->aad_len = 0;
  session_pair->iv_len = iv_len;
  session_pair->digest_len = 0;

  return 0;
}

static int
cryptodev_aead_session_create (vnet_crypto_key_t * const key,
                          struct rte_mempool *sess_pool,
                          struct rte_mempool *sess_priv_pool,
                          key_info_t * session_pair,
                          u32 iv_len, u32 aad_len, u32 digest_len,
                          u32 aead_cryptodev_algo,
                          enum rte_crypto_sym_xform_type xform_type)
{
  struct rte_crypto_sym_xform aead_xform;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  int ret;
  uint8_t dev_id = 0;

  prepare_aead_xform (&aead_xform, DIR_OUT, key,
                       aead_cryptodev_algo,
                       iv_len, aad_len, digest_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
  {
    dev_id = dev_inst->dev_id;
    ret =
      rte_cryptodev_sym_session_init (dev_id, session_pair->keys[0], &aead_xform,
                                     sess_priv_pool);
    if (ret < 0)
      return ret;
    aead_xform.aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;
    ret =
      rte_cryptodev_sym_session_init (dev_id, session_pair->keys[1], &aead_xform,
                                      sess_priv_pool);
    if (ret < 0)
      return ret;
  }

  session_pair->aad_len = aad_len;
  session_pair->iv_len = iv_len;
  session_pair->digest_len = digest_len;

  return 0;
}

static int
cryptodev_auth_session_create (vnet_crypto_key_t * const key,
                              struct rte_mempool *sess_pool,
                              struct rte_mempool *sess_priv_pool,
                              key_info_t * session_pair,
                              u32 digest_len,
                              u32 auth_cryptodev_algo,
                              enum rte_crypto_sym_xform_type xform_type)
{
  struct rte_crypto_sym_xform auth_xform;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  int ret;
  uint8_t dev_id = 0;

  prepare_auth_xform (&auth_xform, DIR_OUT, key,
                      auth_cryptodev_algo, digest_len);

  vec_foreach (dev_inst, cmt->cryptodev_inst)
    {
      dev_id = dev_inst->dev_id;
      ret =
        rte_cryptodev_sym_session_init (dev_id, session_pair->keys[0], &auth_xform,
                                        sess_priv_pool);
      if (ret < 0)
        return ret;

      auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
      ret =
        rte_cryptodev_sym_session_init (dev_id, session_pair->keys[1], &auth_xform,
                                          sess_priv_pool);
      if (ret < 0)
        return ret;
      }

  session_pair->aad_len = 0;
  session_pair->iv_len = 0;
  session_pair->digest_len = digest_len;
  return 0;
}

static void
cryptodev_session_del (struct rte_cryptodev_sym_session *sess)
{
  u32 n_devs, i;

  if (sess == NULL)
    return;

  n_devs = rte_cryptodev_count ();

  for (i = 0; i < n_devs; i++)
    rte_cryptodev_sym_session_clear (i, sess);

  rte_cryptodev_sym_session_free (sess);
}

static_always_inline void
cryptodev_sess_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
                        vnet_crypto_key_index_t idx,
                        u32 digest_len, u32 aad_len)
{
  cryptodev_main_t *cm = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  enum rte_crypto_sym_xform_type xform_type;
  key_info_t *ckey = 0;
  u32 numa;
  u32 cryptodev_algo;
  u32 iv_len, d_len = digest_len;
  int ret = 0;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->keys))
        return;

      ckey = vec_elt_at_index (cm->keys, idx);
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
      return;
    }

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      if (idx >= vec_len (cm->keys))
        return;

      ckey = vec_elt_at_index (cm->keys, idx);

      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      ckey->keys[0] = 0;
      ckey->keys[1] = 0;
    }

  /* create key */
  if (ckey == 0)
    {
      vec_validate (cm->keys, idx + 1);
      ckey = vec_elt_at_index (cm->keys, idx);
    }

  numa = clib_get_current_numa_node ();
  numa_data = vec_elt_at_index (cm->per_numa_data, numa);
  sess_pool = numa_data->sess_pool;
  sess_priv_pool = numa_data->sess_priv_pool;

  ckey->keys[0] = rte_cryptodev_sym_session_create (sess_pool);
  if (!ckey->keys[0])
    {
      ret = -1;
      goto clear_key;
    }

  ckey->keys[1] = rte_cryptodev_sym_session_create (sess_pool);
  if (!ckey->keys[1])
    {
      ret = -1;
      goto clear_key;
    }

  ret = transform_vnet_crypto_type (key->alg, &cryptodev_algo,
                                    &xform_type, &iv_len, &d_len);
  if (ret)
    goto clear_key;

  switch (xform_type)
    {
    case RTE_CRYPTO_SYM_XFORM_CIPHER:
        ret = cryptodev_cipher_session_create (key, sess_pool,
                                               sess_priv_pool,
                                               ckey, iv_len,
                                               cryptodev_algo,
                                               xform_type);
    break;
    case RTE_CRYPTO_SYM_XFORM_AEAD:
      ret = cryptodev_aead_session_create (key, sess_pool, sess_priv_pool,
                                           ckey, iv_len, aad_len, digest_len,
                                           cryptodev_algo,
                                           xform_type);
    break;
    case RTE_CRYPTO_SYM_XFORM_AUTH:
      ret = cryptodev_auth_session_create (key, sess_pool, sess_priv_pool,
                                           ckey, d_len, cryptodev_algo,
                                           xform_type);
    break;
    default:
      ret = -1;
  }

clear_key:
  if (ret != 0)
    {
      cryptodev_session_del (ckey->keys[0]);
      cryptodev_session_del (ckey->keys[1]);
      memset (ckey, 0, sizeof (*ckey));
    }
}

/*static*/ void
cryptodev_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
                       vnet_crypto_key_index_t idx)
{
  cryptodev_sess_handler (vm, kop, idx, ~0, ~0);
}

static_always_inline rte_iova_t
cryptodev_get_data_iova (clib_pmalloc_main_t *pm, void *data)
{
  uword index;

  if (rte_eal_iova_mode() == RTE_IOVA_VA)
    return pointer_to_uword (data);

  index = (pointer_to_uword (data) - pointer_to_uword (pm->base)) >>
      pm->def_log2_page_sz;

  if (PREDICT_FALSE (index >= vec_len (pm->pages)))
    return 0;

  return pointer_to_uword (data) - pm->lookup_table[index];
}

/**
 * Duplicate of vlib_physmem_get_pa (), with validity checking and in/out
 * of place decision.
 *
 * @return 0: valid physical address, in-place operation
 * @return 1: valid physical address, out-of-place operation
 * @return -1: invalid physical address.
 */
static_always_inline int
cryptodev_get_buf_iova (clib_pmalloc_main_t *pm, vnet_crypto_op_t *vop,
                        rte_iova_t *phyaddr_src, rte_iova_t *phyaddr_dst)
{
  int oop = ((vop->dst) && (vop->dst != vop->src));
  uword index;

  if (rte_eal_iova_mode() == RTE_IOVA_VA)
    {
      *phyaddr_src = pointer_to_uword (vop->src);
      *phyaddr_dst = pointer_to_uword (vop->src);

      return oop;
    }

  index = (pointer_to_uword (vop->src) - pointer_to_uword (pm->base)) >>
      pm->def_log2_page_sz;

  if (PREDICT_FALSE (index >= vec_len (pm->pages)))
    return -1;

  *phyaddr_src = pointer_to_uword (vop->src) - pm->lookup_table[index];

  if (oop)
    {
      uword index2 = (pointer_to_uword (vop->dst) -
          pointer_to_uword (pm->base)) >> pm->def_log2_page_sz;

      if (PREDICT_FALSE (index2 >= vec_len (pm->pages)))
        return -1;

      *phyaddr_dst = pointer_to_uword (vop->dst) - pm->lookup_table[index];
    }

  return oop;
}

static_always_inline void
prepare_op_post (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                 cryptodev_iova_t *iova, int oop)
{
  struct rte_crypto_sym_op *sop = &cop->sop;
  struct rte_mbuf *msrc = &cop->msrc;

  msrc->buf_addr = (void *)vop->src;
  msrc->buf_iova = iova->src;
  msrc->buf_len = msrc->data_len = vop->len;

  if (oop)
    {
      struct rte_mbuf *mdst = &cop->mdst;

      sop->m_dst = mdst;
      mdst->buf_addr = (void *)vop->dst;
      mdst->buf_iova = iova->dst;
      mdst->buf_len = mdst->data_len = vop->len;;
    }

  cop->vop = vop;
}

static_always_inline void
enqueue_to_cryptodev (cryptodev_engine_thread_t * cet)
{
  u16 n_enqd = rte_cryptodev_enqueue_burst (cet->cryptodev_id,
                                        cet->cryptodev_q,
                                        cet->ops, cet->cur_op_idx);

  ASSERT (n_enqd == cet->cur_op_idx);

  cet->inflight += n_enqd;
  cet->cur_op_idx = 0;
}

static_always_inline vnet_crypto_op_status_t
decode_crypto_op_status (enum rte_crypto_op_status status)
{
  switch (status)
  {
#define _(a, b) \
    case RTE_CRYPTO_OP_STATUS_##b: \
      return VNET_CRYPTO_OP_STATUS_##a;
    foreach_vnet_crypto_status_conversion
#undef _
    default:
      return VNET_CRYPTO_OP_STATUS_ENGINE_ERR;
  }
}

static_always_inline u32
dequeue_from_cryptodev (cryptodev_engine_thread_t * cet)
{
  struct rte_crypto_op *ops[CRYPTODEV_MAX_INFLIGHT];
  u16 nb_deq = ~0, total_deq = 0, i;

  while (nb_deq >= CRYPTODEV_BURST_SIZE && cet->inflight)
    {
      nb_deq = rte_cryptodev_dequeue_burst (cet->cryptodev_id,
                                            cet->cryptodev_q,
                                            ops, CRYPTODEV_BURST_SIZE);
      cet->inflight -= nb_deq;
      total_deq += nb_deq;

      for (i = 0; i < nb_deq; i++)
        {
          cryptodev_op_t *cop = (cryptodev_op_t *)ops[i];
          vnet_crypto_op_t *vop = cop->vop;

          vop->status = decode_crypto_op_status (ops[i]->status);
          pool_put (cet->crypto_op_pool, cop);
        }
    }

  return total_deq;
}

static_always_inline int
cryptodev_get_resource (vlib_main_t *vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = vec_elt_at_index (cmt->per_thread_data,
                                                     vm->thread_index);
  cryptodev_inst_t *cinst;
  uword idx;

  if (clib_bitmap_count_set_bits (cmt->active_cdev_inst_mask) >=
      vec_len (cmt->cryptodev_inst))
    return -1;

  clib_spinlock_lock (&cmt->tlock);
  idx = clib_bitmap_first_clear (cmt->active_cdev_inst_mask);
  clib_bitmap_set (cmt->active_cdev_inst_mask, idx, 1);
  clib_spinlock_unlock (&cmt->tlock);

  cinst = vec_elt_at_index (cmt->cryptodev_inst, idx);
  cet->cryptodev_id = cinst->dev_id;
  cet->cryptodev_q = cinst->q_id;
  vec_validate_aligned (cet->ops, CRYPTODEV_BURST_SIZE * 2,
                        CLIB_CACHE_LINE_BYTES);
  cet->cur_op_idx = 0;
  cet->inflight = 0;

  return 0;
}

static_always_inline void
cryptodev_alloc_cop_pool (vlib_main_t *vm, cryptodev_engine_thread_t *cet)
{
  cryptodev_op_t *cop;
  u32 i;

  pool_alloc_aligned (cet->crypto_op_pool, CRYPTODEV_NB_CRYPTO_OPS,
                      CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < CRYPTODEV_NB_CRYPTO_OPS; i++)
    {
      cop = cet->crypto_op_pool + i;

      cop->op.phys_addr = vlib_physmem_get_pa (vm, cop);
      cop->op.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
      cop->op.sess_type = RTE_CRYPTO_OP_WITH_SESSION;
      cop->msrc.data_off = 0;
      cop->mdst.data_off = 0;
      cop->sop.aead.data.offset = 0;
      cop->sop.m_src = &cop->msrc;
    };
}

static_always_inline int
cipher_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;

  return cryptodev_get_buf_iova (pm, vop, &iova->src, &iova->dst);
}

static_always_inline int
cipher_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop)
{
  return 0;
}

static_always_inline void
cipher_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                         struct rte_cryptodev_sym_session *sess,
                         u16 iv_len, cryptodev_iova_t *iova)
{
  struct rte_crypto_sym_op *sop = &cop->sop;

  sop->m_dst = NULL;
  sop->session = sess;
  sop->cipher.data.length = vop->len;
  sop->cipher.data.offset = 0;
  memcpy (cop->iv, vop->iv, iv_len);
}

static_always_inline int
aead_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  int oop;

  oop = cryptodev_get_buf_iova (pm, vop, &iova->src, &iova->dst);
  iova->digest = cryptodev_get_data_iova (pm, vop->tag);
  iova->aad = cryptodev_get_data_iova (pm, vop->aad);
  return (iova->digest == 0 || iova->aad == 0) ? -1 : oop;
}

static_always_inline void
aead_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t * vop,
                     struct rte_cryptodev_sym_session *sess,
                     u16 iv_len, cryptodev_iova_t *iova)
{
  struct rte_crypto_sym_op *sop = &cop->sop;
  sop->session = sess;
  sop->aead.data.length = vop->len;
  sop->aead.data.offset = 0;
  sop->aead.aad.data = vop->aad;
  sop->aead.digest.data = vop->tag;
  sop->aead.aad.phys_addr = iova->aad;
  sop->aead.digest.phys_addr = iova->digest;
  memcpy (cop->iv, vop->iv, iv_len);
}

static_always_inline int
aead_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop)
{
  return (key->digest_len != vop->tag_len) || (key->aad_len != vop->aad_len);
}

static_always_inline int
auth_vop_iova_compute (vlib_main_t * vm, vnet_crypto_op_t *vop,
                        cryptodev_iova_t *iova)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  int oop;

  oop = cryptodev_get_buf_iova (pm, vop, &iova->src, &iova->dst);
  iova->digest = cryptodev_get_data_iova (pm, vop->digest);

  return iova->digest == 0 ? -1 : oop;
}

static_always_inline int
auth_op_need_key_update (key_info_t *key, vnet_crypto_op_t *vop)
{
  return key->digest_len != vop->digest_len;
}

static_always_inline void
auth_op_translate_vop (cryptodev_op_t *cop, vnet_crypto_op_t *vop,
                         struct rte_cryptodev_sym_session *sess,
                         u16 iv_len, cryptodev_iova_t *iova)
{
  struct rte_crypto_sym_op *sop = &cop->sop;

  sop->m_dst = NULL;
  sop->session = sess;
  sop->auth.data.length = vop->len;
  sop->auth.data.offset = 0;
  sop->auth.digest.data = vop->digest;
  sop->auth.digest.phys_addr = iova->digest;
}

static_always_inline u32
cryptodev_queue_handler (vlib_main_t * vm, u32 thread_idx,
                         vnet_crypto_queue_t * q,
                         _pre_iova_compute iova_compute,
                         _need_key_update need_key_update,
                         _translate_vop translate_cop,
                         u32 dir, u32 use_tag)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vnet_crypto_op_t *vop;
  cryptodev_engine_thread_t *cet = vec_elt_at_index (cmt->per_thread_data,
                                                     vm->thread_index);
  key_info_t *key = 0;
  u32 last_key_idx = ~0;
  u16 fetch_sz;
  u32 atomic = (vm->thread_index != thread_idx);

  if (PREDICT_FALSE (cet->crypto_op_pool == 0))
    {
      if (cryptodev_get_resource (vm) < 0)
        return 0;
      cryptodev_alloc_cop_pool (vm, cet);
    }

  fetch_sz = CRYPTODEV_NB_CRYPTO_OPS - cet->inflight - cet->cur_op_idx;

  while ((vop = vnet_crypto_async_get_pending_op (q, atomic)) && fetch_sz)
    {
      cryptodev_iova_t iova = {0};
      cryptodev_op_t *cop;
      int oop;

      oop = iova_compute (vm, vop, &iova);
      if (PREDICT_FALSE (oop < 0))
        {
          vop->status = VNET_CRYPTO_OP_STATUS_ENGINE_ERR;
          continue;
        }

      if (last_key_idx != vop->key_index)
        {
          key = vec_elt_at_index (cmt->keys, vop->key_index);
          last_key_idx = vop->key_index;

          if (PREDICT_FALSE (need_key_update (key, vop) != 0))
            cryptodev_sess_handler (vm, VNET_CRYPTO_KEY_OP_MODIFY,
                                   vop->key_index, use_tag ?
                                    vop->tag_len : vop->digest_len,
                                   vop->aad_len);

          if (PREDICT_FALSE (key->keys[dir] == 0))
            {
              vop->status = VNET_CRYPTO_OP_STATUS_ENGINE_ERR;
              continue;
            }
        }

      pool_get_aligned (cet->crypto_op_pool, cop, CLIB_CACHE_LINE_BYTES);
      CLIB_PREFETCH (&cop->sop, sizeof (struct rte_crypto_sym_op), STORE);
      CLIB_PREFETCH (&cop->msrc, sizeof (struct rte_mbuf), STORE);
      CLIB_PREFETCH (&cop->mdst, sizeof (struct rte_mbuf) + sizeof (uword),
                     STORE);

      vec_validate_aligned (cet->ops, cet->cur_op_idx, CLIB_CACHE_LINE_BYTES);

      translate_cop (cop, vop, key->keys[dir], key->iv_len, &iova);
      prepare_op_post (cop, vop, &iova, oop);

      cet->ops [cet->cur_op_idx++] = (struct rte_crypto_op *)cop;

      if (PREDICT_FALSE (cet->cur_op_idx >= CRYPTODEV_BURST_SIZE))
        {
          enqueue_to_cryptodev (cet);
          cet->enc_counter = 0;
        }

      fetch_sz--;
    }

  if (PREDICT_FALSE (cet->enc_counter++ >= CRYPTODEV_MAX_TIMER))
    {
      enqueue_to_cryptodev (cet);
      cet->enc_counter = 0;
    }

  if (cet->inflight >= CRYPTODEV_MAX_INFLIGHT ||
      cet->dec_counter++ >= CRYPTODEV_MAX_TIMER)
    {
      cet->dec_counter = 0;
      return dequeue_from_cryptodev (cet);
    }

  return 0;
}

#define _(v, t, c, i) \
static_always_inline u32 \
cryptodev_queue_handler_##v##_enc (vlib_main_t * vm, u32 thread_idx, \
                                vnet_crypto_queue_t * q) \
{ \
  return cryptodev_queue_handler (vm, thread_idx, q, cipher_vop_iova_compute, \
                                  cipher_op_need_key_update, \
                                  cipher_op_translate_vop, DIR_OUT, 0); \
} \
static_always_inline u32 \
cryptodev_queue_handler_##v##_dec (vlib_main_t * vm, u32 thread_idx, \
                                vnet_crypto_queue_t * q) \
{ \
  return cryptodev_queue_handler (vm, thread_idx, q, cipher_vop_iova_compute, \
                                  cipher_op_need_key_update, \
                                  cipher_op_translate_vop, DIR_IN, 0); \
}
foreach_vnet_cipher_crypto_conversion
#undef _

#define _(v, t, c, i) \
static_always_inline u32 \
cryptodev_queue_handler_##v##_enc (vlib_main_t * vm, u32 thread_idx, \
                                vnet_crypto_queue_t * q) \
{ \
  return cryptodev_queue_handler (vm, thread_idx, q, aead_vop_iova_compute, \
                                  aead_op_need_key_update, \
                                  aead_op_translate_vop, DIR_OUT, 1); \
} \
static_always_inline u32 \
cryptodev_queue_handler_##v##_dec (vlib_main_t * vm, u32 thread_idx, \
                                vnet_crypto_queue_t * q) \
{ \
  return cryptodev_queue_handler (vm, thread_idx, q, aead_vop_iova_compute, \
                                  aead_op_need_key_update, \
                                  aead_op_translate_vop, DIR_IN, 1); \
}
foreach_vnet_aead_crypto_conversion
#undef _

#define _(v, t, c, d) \
static_always_inline u32 \
cryptodev_queue_handler_HMAC_##v (vlib_main_t * vm, u32 thread_idx, \
                             vnet_crypto_queue_t * q) \
{ \
  return cryptodev_queue_handler (vm, thread_idx, q, auth_vop_iova_compute, \
                                  auth_op_need_key_update, \
                                  auth_op_translate_vop, DIR_OUT, 0); \
}

foreach_vnet_hmac_crypto_conversion
#undef _

static int
check_cryptodev_alg_support (u32 dev_id)
{
  const struct rte_cryptodev_symmetric_capability *cap;
  struct rte_cryptodev_sym_capability_idx cap_idx;

#define _(v, t, c, i) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##t; \
  cap_idx.algo.cipher = RTE_CRYPTO_##t##_##c; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##t##_##c;

  foreach_vnet_cipher_crypto_conversion
#undef _

#define _(v, t, c, d) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##t; \
  cap_idx.algo.auth = RTE_CRYPTO_##t##_##c; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##t##_##c;

  foreach_vnet_hmac_crypto_conversion
#undef _

#define _(v, t, c, i) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##t; \
  cap_idx.algo.aead = RTE_CRYPTO_##t##_##c; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##t##_##c;

  foreach_vnet_aead_crypto_conversion
#undef _

  return 0;
}

static void
cryptodev_probe (vlib_main_t *vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  u32 n_cryptodevs = rte_cryptodev_count ();
  u32 numa = vm->numa_node;
  u32 i;

  numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

  for (i = 0; i < n_cryptodevs; i++)
    {
      struct rte_cryptodev_info info;
      struct rte_cryptodev *cdev;
      i32 qp_setup_err = 0;
      u32 n_cdev_inst;
      u32 j;

      cdev = rte_cryptodev_pmd_get_dev (i);
      rte_cryptodev_info_get (i, &info);

      /**
       * Cryptodev is NUMA sensitive, for performance reason the device
       * lies in different numa node is not used.
       **/
      if (rte_cryptodev_socket_id (i) != numa)
        continue;

      if (check_cryptodev_alg_support (i) != 0)
        continue;

      n_cdev_inst = vec_len (cmt->cryptodev_inst);

      /** If the device is already started, we reuse it, otherwise configure
       *  both the device and queue pair.
       **/
      if (!cdev->data->dev_started)
        {
          struct rte_cryptodev_config cfg;

          cfg.socket_id = vm->numa_node;
          cfg.nb_queue_pairs = info.max_nb_queue_pairs;

          rte_cryptodev_configure (i, &cfg);

          for (j = 0; j < info.max_nb_queue_pairs; j++)
            {
              struct rte_cryptodev_qp_conf qp_cfg;

              int ret;

              if (qp_setup_err)
                continue;

              qp_cfg.mp_session = numa_data->sess_pool;
              qp_cfg.mp_session_private = numa_data->sess_priv_pool;
              qp_cfg.nb_descriptors = CRYPTODEV_NB_CRYPTO_OPS;

              ret = rte_cryptodev_queue_pair_setup (i, j, &qp_cfg, numa);
              if (ret)
                qp_setup_err = 1;
            }

          /* start the device */
          rte_cryptodev_start (i);
        }

      if (qp_setup_err)
        continue;

      for (j = 0; j < info.max_nb_queue_pairs; j++)
        {
          cryptodev_inst_t *cdev_inst;

          vec_validate (cmt->cryptodev_inst, n_cdev_inst + j);
          cdev_inst = vec_elt_at_index (cmt->cryptodev_inst, n_cdev_inst + j);
          cdev_inst->desc = vec_new (char , strlen(info.device->name) + 10);
          cdev_inst->dev_id = i;
          cdev_inst->q_id = j;

          snprintf(cdev_inst->desc, 128, "%s_q%u", info.device->name, j);
        }
    }
}

static i32
cryptodev_get_session_sz (void)
{
  u32 sess_data_sz = 0, i;

  if (rte_cryptodev_count () == 0)
    return -1;

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      u32 dev_sess_sz =
          rte_cryptodev_sym_get_private_session_size (i);

      sess_data_sz = dev_sess_sz > sess_data_sz ? dev_sess_sz : sess_data_sz;
    }

  return sess_data_sz;
}

static void
dpdk_disable_cryptodev_engine (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
//  cryptodev_engine_thread_t *cet;
  u32 numa;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
    {
      cryptodev_numa_data_t *numa_data;

      numa_data = vec_elt_at_index(cmt->per_numa_data, numa);

      if (numa_data->sess_pool)
        rte_mempool_free (numa_data->sess_pool);
      if (numa_data->sess_priv_pool)
        rte_mempool_free (numa_data->sess_priv_pool);
    }));

  vec_foreach (cet, cmt->per_thread_data)
  {
    if (cet->crypto_op_pool)
      pool_free (cet->crypto_op_pool);
  }

  /* *INDENT-On* */
}

clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_workers = vlib_thread_main.n_vlib_mains - 1;
  u32 n_numa, numa;
  i32 sess_sz;
  u32 eidx;
  u8 *name = 0;
  clib_error_t *error;

  n_numa = clib_bitmap_count_set_bits (tm->cpu_socket_bitmap);

  sess_sz = cryptodev_get_session_sz();
  if (sess_sz < 0)
    {
      error = clib_error_return (0, "No Cryptodev available");
      return error;
    }

  vec_validate (cmt->per_numa_data, n_numa);

  /* *INDENT-OFF* */
  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
    {
      cryptodev_numa_data_t *numa_data;
      struct rte_mempool *mp;

      numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

      name = format (0, "vcryptodev_sess_pool_%u", numa);
      mp = rte_cryptodev_sym_session_pool_create ((char *) name,
                                                  CRYPTODEV_NB_SESSION,
                                                  0, 0, 0, numa);
      if (!mp)
        {
          error = clib_error_return (0, "Not enough memory for mp %s", name);
          goto err_handling;
        }
      vec_free (name);

      numa_data->sess_pool = mp;

      name = format (0, "vcryptodev_sess_ppool_%u", numa);
      mp = rte_mempool_create ((char *) name, CRYPTODEV_NB_SESSION, sess_sz, 0,
                               0, NULL, NULL, NULL, NULL, numa, 0);
      if (!mp)
        {
          error = clib_error_return (0, "Not enough memory for mp %s", name);
          goto err_handling;
        }

      vec_free (name);

      numa_data->sess_priv_pool = mp;
  }));
  /* *INDENT-On* */

  cryptodev_probe (vm);

  clib_bitmap_vec_validate (cmt->active_cdev_inst_mask, n_workers);
  clib_spinlock_init (&cmt->tlock);

  vec_validate_aligned(cmt->per_thread_data, n_workers, CLIB_CACHE_LINE_BYTES);

  eidx = vnet_crypto_register_engine (vm, "dpdk-cryptodev", 80,
                                      "DPDK Cryptodev Engine");
  // cipher algorithms

#define _(v, t, c, i) \
  vnet_crypto_register_queue_handler (vm, eidx, \
                                      VNET_CRYPTO_OP_##v##_ENC, \
                                      cryptodev_queue_handler_##v##_enc);\
  vnet_crypto_register_queue_handler (vm, eidx, \
                                      VNET_CRYPTO_OP_##v##_DEC, \
                                      cryptodev_queue_handler_##v##_dec);
  foreach_vnet_cipher_crypto_conversion
#undef _

#define _(v, t, c, i) \
  vnet_crypto_register_queue_handler (vm, eidx, \
                                      VNET_CRYPTO_OP_##v##_ENC, \
                                      cryptodev_queue_handler_##v##_enc);\
  vnet_crypto_register_queue_handler (vm, eidx, \
                                      VNET_CRYPTO_OP_##v##_DEC, \
                                      cryptodev_queue_handler_##v##_dec);
  foreach_vnet_aead_crypto_conversion
#undef _

#define _(v, t, c, d) \
  vnet_crypto_register_queue_handler (vm, eidx, \
                                      VNET_CRYPTO_OP_##v##_HMAC, \
                                      cryptodev_queue_handler_HMAC_##v);

  foreach_vnet_hmac_crypto_conversion
#undef _

  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);

  return 0;

err_handling:
  dpdk_disable_cryptodev_engine (vm);

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

